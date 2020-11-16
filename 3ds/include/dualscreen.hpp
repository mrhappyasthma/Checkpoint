/*
 *   This file is part of Checkpoint
 *   Copyright (C) 2017-2020 Bernardo Giordano, FlagBrew
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *   Additional Terms 7.b and 7.c of GPLv3 apply to this file:
 *       * Requiring preservation of specified reasonable legal notices or
 *         author attributions in that material or in the Appropriate Legal
 *         Notices displayed by works containing it.
 *       * Prohibiting misrepresentation of the origin of that material,
 *         or requiring that modified versions of such material be marked in
 *         reasonable ways as different from the original version.
 */

#ifndef DUALSCREEN_HPP
#define DUALSCREEN_HPP

#include "Screen.hpp"
#include "Overlay.hpp"
#include "drawdata.hpp"

class DualScreenScreen : public Screen {
protected:
    virtual void draw(DrawDataHolder& d) const final {
        d.citro.targetTop();
        drawTop(d);
        d.citro.targetBottom();
        drawBottom(d);
    }

    virtual void drawTop(DrawDataHolder& d) const = 0;
    virtual void drawBottom(DrawDataHolder& d) const = 0;
};

class DualScreenOverlay : public Overlay {
protected:
    DualScreenOverlay(Screen& scr) : Overlay(scr)
    { }

    virtual void draw(DrawDataHolder& d) const final {
        d.citro.targetTop();
        drawTop(d);
        d.citro.targetBottom();
        drawBottom(d);
    }
    virtual void drawTop(DrawDataHolder& d) const = 0;
    virtual void drawBottom(DrawDataHolder& d) const = 0;
};

#endif
