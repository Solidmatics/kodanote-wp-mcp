/* "Used in" panel for patterns, in the post editor and the Site Editor. No build step. */
( function ( wp ) {
	if ( ! wp || ! wp.plugins || ! wp.data || ! wp.element || ! wp.apiFetch ) {
		return;
	}
	var Panel = ( wp.editor && wp.editor.PluginDocumentSettingPanel ) || ( wp.editPost && wp.editPost.PluginDocumentSettingPanel );
	if ( ! Panel ) {
		return;
	}
	var el = wp.element.createElement;

	function describe( item ) {
		var label = item.title + ' (' + item.type_label + ( 'publish' === item.status ? '' : ', ' + item.status ) + ')';
		var href = item.edit_link || item.link;
		return el( 'li', { key: item.id }, href ? el( 'a', { href: href }, label ) : label );
	}

	function body( usage ) {
		if ( ! usage ) {
			return el( 'p', null, 'Checking where this pattern is used…' );
		}
		if ( usage.failed ) {
			return el( 'p', null, 'Usage could not be loaded. Save the pattern and reload to try again.' );
		}
		var parts = [];
		if ( ! usage.synced ) {
			parts.push( el( 'p', { key: 'unsynced' }, 'This pattern is not synced. Inserted copies are independent and are not tracked.' ) );
		}
		if ( ! usage.total ) {
			if ( usage.synced ) {
				parts.push( el( 'p', { key: 'none' }, 'Not used anywhere yet.' ) );
			}
			return parts;
		}
		parts.push( el( 'p', { key: 'summary' }, 1 === usage.total ? 'Editing this pattern changes 1 place:' : 'Editing this pattern changes ' + usage.total + ' places:' ) );
		parts.push( el( 'ul', { key: 'items' }, usage.items.map( describe ) ) );
		var more = usage.total - usage.hidden - usage.items.length;
		if ( more > 0 ) {
			parts.push( el( 'p', { key: 'more' }, 'and ' + more + ' more.' ) );
		}
		if ( usage.hidden ) {
			parts.push( el( 'p', { key: 'hidden' }, usage.hidden + ( 1 === usage.hidden ? ' place you cannot open.' : ' places you cannot open.' ) ) );
		}
		return parts;
	}

	function UsedIn() {
		var post = wp.data.useSelect( function ( select ) {
			var editor = select( 'core/editor' );
			return { type: editor.getCurrentPostType(), id: editor.getCurrentPostId() };
		}, [] );
		var state = wp.element.useState( null );
		var usage = state[ 0 ];
		var setUsage = state[ 1 ];
		var isPattern = 'wp_block' === post.type && !! post.id && ! isNaN( parseInt( post.id, 10 ) );

		wp.element.useEffect( function () {
			if ( ! isPattern ) {
				return undefined;
			}
			var active = true;
			setUsage( null );
			wp.apiFetch( { path: '/kodanote-mcp/v1/patterns/' + parseInt( post.id, 10 ) + '/usage' } ).then(
				function ( data ) {
					if ( active ) {
						setUsage( data );
					}
				},
				function () {
					if ( active ) {
						setUsage( { failed: true } );
					}
				}
			);
			return function () {
				active = false;
			};
		}, [ isPattern, post.id ] );

		if ( ! isPattern ) {
			return null;
		}
		return el( Panel, { name: 'kodanote-mcp-pattern-usage', title: 'Used in', className: 'kodanote-mcp-pattern-usage' }, body( usage ) );
	}

	wp.plugins.registerPlugin( 'kodanote-mcp-pattern-usage', { render: UsedIn } );
} )( window.wp );
