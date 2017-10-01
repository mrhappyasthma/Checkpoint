/*  This file is part of Checkpoint
>	Copyright (C) 2017 Bernardo Giordano
>
>   This program is free software: you can redistribute it and/or modify
>   it under the terms of the GNU General Public License as published by
>   the Free Software Foundation, either version 3 of the License, or
>   (at your option) any later version.
>
>   This program is distributed in the hope that it will be useful,
>   but WITHOUT ANY WARRANTY; without even the implied warranty of
>   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
>   GNU General Public License for more details.
>
>   You should have received a copy of the GNU General Public License
>   along with this program.  If not, see <http://www.gnu.org/licenses/>.
>   See LICENSE for information.
*/

#include "util.h"

void servicesExit(void)
{
	archiveExit();
	amExit();
	srvExit();
	hidExit();
	pp2d_exit();
	sdmcExit();
}

void servicesInit(void)
{
	Result res = 0;
	
	sdmcInit();
	pp2d_init();
	hidInit();
	srvInit();
	amInit();
	
	res = archiveInit();
	if (R_FAILED(res))
	{
		createError(res, "SDMC archive init failed.");
	}
	
	mkdir("sdmc:/Checkpoint", 777);
	mkdir("sdmc:/Checkpoint/saves", 777);
	mkdir("sdmc:/Checkpoint/extdata", 777);
	
	pp2d_set_screen_color(GFX_TOP, COLOR_BACKGROUND);
	pp2d_set_screen_color(GFX_BOTTOM, COLOR_BACKGROUND);
}