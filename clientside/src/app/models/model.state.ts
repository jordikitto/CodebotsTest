/*
 * @bot-written
 * 
 * WARNING AND NOTICE
 * Any access, download, storage, and/or use of this source code is subject to the terms and conditions of the
 * Full Software Licence as accepted by you before being granted access to this source code and other materials,
 * the terms of which can be accessed on the Codebots website at https://codebots.com/full-software-licence. Any
 * commercial use in contravention of the terms of the Full Software Licence may be pursued by Codebots through
 * licence termination and further legal action, and be required to indemnify Codebots for any loss or damage,
 * including interest and costs. You are deemed to have accepted the terms of the Full Software Licence on any
 * access, download, storage, and/or use of this source code.
 * 
 * BOT WARNING
 * This file is bot-written.
 * Any changes out side of "protected regions" will be lost next time the bot makes any changes.
 */

import {Params, RouterStateSnapshot} from '@angular/router';
import {RouterReducerState, RouterStateSerializer} from '@ngrx/router-store';
import {RoutingEffect} from '../lib/routing/routing.effect';
import {QueryParams} from '../lib/services/http/interfaces';
import {AbstractModel} from '../lib/models/abstract.model';

// % protected region % [Add any additional imports here] off begin
// % protected region % [Add any additional imports here] end

/**
 * The State of a collection of the model
 * This would store the queryParams of specific collection, which could be shared through the store
 */
export interface CollectionState {
	/**
	 * The query parameters to be used for querying of this collection
	 */
	queryParams: QueryParams;

	/**
	 * The total number of results on the server that match the queryParams
	 */
	collectionCount: number;

	/**
	 * The ids of the data in this collection
	 */
	ids?: string[];
}

/**
 * Types of audit query.
 */
export enum AuditQueryType {
	CREATE = 'CREATE',
	UPDATE = 'UPDATE',
	DELETE = 'DELETE'
}

/**
 * State containing audits against a specific entity.
 */
export interface AbstractModelAudit<E extends AbstractModel> {
	entity: E;
	timestamp: string;
	type: AuditQueryType;
	authorId: string;
	authorFirstName: string;
	authorLastName: string;
	// % protected region % [Add any model audit properties here] off begin
	// % protected region % [Add any model audit properties here] end
}

/**
 * State containing all models in the current application. This acts essentially as the central store of models for the
 * application.
 */
export interface ModelState {
}

/**
 * Initial model state of the application.
 */
export const initialModelState: ModelState = {
};

/**
 * State containing all everything in the current application. This acts essentially as the central store of the
 * application, including the router and the model state.
 */
export interface AppState {
	router: RouterReducerState<RouterState>;
	models: ModelState;
	// % protected region % [Add any additional app state definition here] off begin
	// % protected region % [Add any additional app state definition here] end
}

/**
 * List of all effects for each model in the application.
 */
export const effects = [
	RoutingEffect,
	// % protected region % [Add any additional effects here] off begin
	// % protected region % [Add any additional effects here] end
];

/**
 * Define the state for the Angular router. Since the original one contains many unused data which can be removed
 * otherwise, this interface is used with the custom serialiser below to provide a simpler router state.
 */
export interface RouterState {
	url: string;
	urls: string[];
	params: Params;
	queryParams: Params;
	data: any;
	// % protected region % [Add any additional properties for RouterState here] off begin
	// % protected region % [Add any additional properties for RouterState here] end
}

/**
 * Define the initial state for router when first bootstrapped.
 */
export const initialRouterState: RouterReducerState<RouterState> = {
	state: {
		url: '/',
		urls: [],
		params: [],
		queryParams: [],
		data: {},
		// % protected region % [Add any additional initial state for RouterState here] off begin
		// % protected region % [Add any additional initial state for RouterState here] end
	},
	navigationId: -1
};

/**
 * Custom serializer used for parsing the original router state provided by Angular.
 */
export class CustomSerializer implements RouterStateSerializer<RouterState> {
	serialize(routerState: RouterStateSnapshot): RouterState {
		let route = routerState.root;
		const urls: string[] = [];

		while (route.firstChild) {
			route.firstChild.url.forEach(u => urls.push(u.path));
			route = route.firstChild;
		}

		const {
			url,
			root: {
				queryParams,
				data,
				// % protected region % [Add any additional extraction of routerState properties here] off begin
				// % protected region % [Add any additional extraction of routerState properties here] end
			}
		} = routerState;
		const {params} = route;

		// Only return an object including the URL, params and query params
		// instead of the entire snapshot
		return {
			url,
			urls,
			params,
			queryParams,
			data,
			// % protected region % [Add any additional properties to be returned here] off begin
			// % protected region % [Add any additional properties to be returned here] end
		};
	}
}

// % protected region % [Add any additional stuffs here] off begin
// % protected region % [Add any additional stuffs here] end
