<?php
namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

/** Persistent, non-autoloaded OAuth records. Secrets are stored only as SHA-256 keys. */
final class Store {
	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'kodanote_mcp';
	}

	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table = self::table();
		$collation = $wpdb->get_charset_collate();
		dbDelta( "CREATE TABLE $table (
			record_key varchar(191) NOT NULL,
			kind varchar(24) NOT NULL,
			payload longtext NOT NULL,
			expires bigint(20) unsigned NOT NULL,
			consumed tinyint(1) NOT NULL DEFAULT 0,
			PRIMARY KEY  (record_key),
			KEY expiry (expires),
			KEY kind (kind)
		) $collation;" );
	}

	public static function put( string $kind, string $id, array $data, int $expires ): bool {
		global $wpdb;
		return false !== $wpdb->insert( self::table(), array(
			'record_key' => $kind . ':' . hash( 'sha256', $id ),
			'kind' => $kind, 'payload' => wp_json_encode( $data ), 'expires' => $expires,
		), array( '%s', '%s', '%s', '%d' ) );
	}

	public static function get( string $kind, string $id ): ?array {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare(
			'SELECT payload, consumed, expires FROM ' . self::table() . ' WHERE record_key = %s AND expires > %d',
			$kind . ':' . hash( 'sha256', $id ), time()
		), ARRAY_A );
		if ( ! $row ) { return null; }
		$data = json_decode( $row['payload'], true );
		if ( ! is_array( $data ) ) { return null; }
		$data['_consumed'] = (bool) $row['consumed'];
		$data['_expires'] = (int) $row['expires'];
		return $data;
	}

	/** Atomic claim prevents concurrent code redemption / refresh replay. Tombstones detect replay. */
	public static function consume( string $kind, string $id ): bool {
		global $wpdb;
		return 1 === $wpdb->query( $wpdb->prepare(
			'UPDATE ' . self::table() . ' SET consumed = 1 WHERE record_key = %s AND consumed = 0 AND expires > %d',
			$kind . ':' . hash( 'sha256', $id ), time()
		) );
	}

	public static function delete( string $kind, string $id ): void {
		global $wpdb;
		$wpdb->delete( self::table(), array( 'record_key' => $kind . ':' . hash( 'sha256', $id ) ), array( '%s' ) );
	}

	/** A revocation tombstone also covers a concurrent code exchange about to create its grant. */
	public static function revoke_grant( string $id ): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare(
			'INSERT IGNORE INTO ' . self::table() . " (record_key, kind, payload, expires) VALUES (%s, 'revoked', '{}', %d)",
			'revoked:' . hash( 'sha256', $id ), time() + 31 * DAY_IN_SECONDS
		) );
		self::delete( 'grant', $id );
	}

	public static function cleanup(): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table() . ' WHERE expires <= %d', time() ) );
	}

	public static function grants_for_user( int $user_id ): array {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT payload FROM ' . self::table() . ' WHERE kind = %s AND expires > %d', 'grant', time() ), ARRAY_A );
		$result = array();
		foreach ( $rows as $row ) {
			$grant = json_decode( $row['payload'], true );
			if ( is_array( $grant ) && (int) $grant['user_id'] === $user_id ) { $result[] = $grant; }
		}
		return $result;
	}

	/** Persistent, atomic fixed-window throttle, independent of WordPress object-cache topology. */
	public static function rate_limit( string $bucket, int $limit, int $window ): bool {
		global $wpdb;
		$key = 'rate:' . hash( 'sha256', $bucket . ':' . (string) intdiv( time(), $window ) );
		$table = self::table();
		$wpdb->query( $wpdb->prepare(
			"INSERT INTO $table (record_key, kind, payload, expires) VALUES (%s, 'rate', '1', %d) ON DUPLICATE KEY UPDATE payload = CAST(payload AS UNSIGNED) + 1",
			$key, time() + $window * 2
		) );
		$count = $wpdb->get_var( $wpdb->prepare( "SELECT payload FROM $table WHERE record_key = %s", $key ) );
		return null !== $count && (int) $count <= $limit;
	}
}
