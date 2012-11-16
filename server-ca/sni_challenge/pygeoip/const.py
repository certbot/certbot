"""
Constants needed for parsing binary GeoIP databases. It is part of the pygeoip
package.

@author: Jennifer Ennis <zaylea at gmail dot com>

@license:
Copyright(C) 2004 MaxMind LLC

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/lgpl.txt>.
"""

GEOIP_STANDARD = 0
GEOIP_MEMORY_CACHE = 1

DMA_MAP = {
    500 : 'Portland-Auburn, ME',
    501 : 'New York, NY',
    502 : 'Binghamton, NY',
    503 : 'Macon, GA',
    504 : 'Philadelphia, PA',
    505 : 'Detroit, MI',
    506 : 'Boston, MA',
    507 : 'Savannah, GA',
    508 : 'Pittsburgh, PA',
    509 : 'Ft Wayne, IN',
    510 : 'Cleveland, OH',
    511 : 'Washington, DC',
    512 : 'Baltimore, MD',
    513 : 'Flint, MI',
    514 : 'Buffalo, NY',
    515 : 'Cincinnati, OH',
    516 : 'Erie, PA',
    517 : 'Charlotte, NC',
    518 : 'Greensboro, NC',
    519 : 'Charleston, SC',
    520 : 'Augusta, GA',
    521 : 'Providence, RI',
    522 : 'Columbus, GA',
    523 : 'Burlington, VT',
    524 : 'Atlanta, GA',
    525 : 'Albany, GA',
    526 : 'Utica-Rome, NY',
    527 : 'Indianapolis, IN',
    528 : 'Miami, FL',
    529 : 'Louisville, KY',
    530 : 'Tallahassee, FL',
    531 : 'Tri-Cities, TN',
    532 : 'Albany-Schenectady-Troy, NY',
    533 : 'Hartford, CT',
    534 : 'Orlando, FL',
    535 : 'Columbus, OH',
    536 : 'Youngstown-Warren, OH',
    537 : 'Bangor, ME',
    538 : 'Rochester, NY',
    539 : 'Tampa, FL',
    540 : 'Traverse City-Cadillac, MI',
    541 : 'Lexington, KY',
    542 : 'Dayton, OH',
    543 : 'Springfield-Holyoke, MA',
    544 : 'Norfolk-Portsmouth, VA',
    545 : 'Greenville-New Bern-Washington, NC',
    546 : 'Columbia, SC',
    547 : 'Toledo, OH',
    548 : 'West Palm Beach, FL',
    549 : 'Watertown, NY',
    550 : 'Wilmington, NC',
    551 : 'Lansing, MI',
    552 : 'Presque Isle, ME',
    553 : 'Marquette, MI',
    554 : 'Wheeling, WV',
    555 : 'Syracuse, NY',
    556 : 'Richmond-Petersburg, VA',
    557 : 'Knoxville, TN',
    558 : 'Lima, OH',
    559 : 'Bluefield-Beckley-Oak Hill, WV',
    560 : 'Raleigh-Durham, NC',
    561 : 'Jacksonville, FL',
    563 : 'Grand Rapids, MI',
    564 : 'Charleston-Huntington, WV',
    565 : 'Elmira, NY',
    566 : 'Harrisburg-Lancaster-Lebanon-York, PA',
    567 : 'Greenville-Spartenburg, SC',
    569 : 'Harrisonburg, VA',
    570 : 'Florence-Myrtle Beach, SC',
    571 : 'Ft Myers, FL',
    573 : 'Roanoke-Lynchburg, VA',
    574 : 'Johnstown-Altoona, PA',
    575 : 'Chattanooga, TN',
    576 : 'Salisbury, MD',
    577 : 'Wilkes Barre-Scranton, PA',
    581 : 'Terre Haute, IN',
    582 : 'Lafayette, IN',
    583 : 'Alpena, MI',
    584 : 'Charlottesville, VA',
    588 : 'South Bend, IN',
    592 : 'Gainesville, FL',
    596 : 'Zanesville, OH',
    597 : 'Parkersburg, WV',
    598 : 'Clarksburg-Weston, WV',
    600 : 'Corpus Christi, TX',
    602 : 'Chicago, IL',
    603 : 'Joplin-Pittsburg, MO',
    604 : 'Columbia-Jefferson City, MO',
    605 : 'Topeka, KS',
    606 : 'Dothan, AL',
    609 : 'St Louis, MO',
    610 : 'Rockford, IL',
    611 : 'Rochester-Mason City-Austin, MN',
    612 : 'Shreveport, LA',
    613 : 'Minneapolis-St Paul, MN',
    616 : 'Kansas City, MO',
    617 : 'Milwaukee, WI',
    618 : 'Houston, TX',
    619 : 'Springfield, MO',
    620 : 'Tuscaloosa, AL',
    622 : 'New Orleans, LA',
    623 : 'Dallas-Fort Worth, TX',
    624 : 'Sioux City, IA',
    625 : 'Waco-Temple-Bryan, TX',
    626 : 'Victoria, TX',
    627 : 'Wichita Falls, TX',
    628 : 'Monroe, LA',
    630 : 'Birmingham, AL',
    631 : 'Ottumwa-Kirksville, IA',
    632 : 'Paducah, KY',
    633 : 'Odessa-Midland, TX',
    634 : 'Amarillo, TX',
    635 : 'Austin, TX',
    636 : 'Harlingen, TX',
    637 : 'Cedar Rapids-Waterloo, IA',
    638 : 'St Joseph, MO',
    639 : 'Jackson, TN',
    640 : 'Memphis, TN',
    641 : 'San Antonio, TX',
    642 : 'Lafayette, LA',
    643 : 'Lake Charles, LA',
    644 : 'Alexandria, LA',
    646 : 'Anniston, AL',
    647 : 'Greenwood-Greenville, MS',
    648 : 'Champaign-Springfield-Decatur, IL',
    649 : 'Evansville, IN',
    650 : 'Oklahoma City, OK',
    651 : 'Lubbock, TX',
    652 : 'Omaha, NE',
    656 : 'Panama City, FL',
    657 : 'Sherman, TX',
    658 : 'Green Bay-Appleton, WI',
    659 : 'Nashville, TN',
    661 : 'San Angelo, TX',
    662 : 'Abilene-Sweetwater, TX',
    669 : 'Madison, WI',
    670 : 'Ft Smith-Fay-Springfield, AR',
    671 : 'Tulsa, OK',
    673 : 'Columbus-Tupelo-West Point, MS',
    675 : 'Peoria-Bloomington, IL',
    676 : 'Duluth, MN',
    678 : 'Wichita, KS',
    679 : 'Des Moines, IA',
    682 : 'Davenport-Rock Island-Moline, IL',
    686 : 'Mobile, AL',
    687 : 'Minot-Bismarck-Dickinson, ND',
    691 : 'Huntsville, AL',
    692 : 'Beaumont-Port Author, TX',
    693 : 'Little Rock-Pine Bluff, AR',
    698 : 'Montgomery, AL',
    702 : 'La Crosse-Eau Claire, WI',
    705 : 'Wausau-Rhinelander, WI',
    709 : 'Tyler-Longview, TX',
    710 : 'Hattiesburg-Laurel, MS',
    711 : 'Meridian, MS',
    716 : 'Baton Rouge, LA',
    717 : 'Quincy, IL',
    718 : 'Jackson, MS',
    722 : 'Lincoln-Hastings, NE',
    724 : 'Fargo-Valley City, ND',
    725 : 'Sioux Falls, SD',
    734 : 'Jonesboro, AR',
    736 : 'Bowling Green, KY',
    737 : 'Mankato, MN',
    740 : 'North Platte, NE',
    743 : 'Anchorage, AK',
    744 : 'Honolulu, HI',
    745 : 'Fairbanks, AK',
    746 : 'Biloxi-Gulfport, MS',
    747 : 'Juneau, AK',
    749 : 'Laredo, TX',
    751 : 'Denver, CO',
    752 : 'Colorado Springs, CO',
    753 : 'Phoenix, AZ',
    754 : 'Butte-Bozeman, MT',
    755 : 'Great Falls, MT',
    756 : 'Billings, MT',
    757 : 'Boise, ID',
    758 : 'Idaho Falls-Pocatello, ID',
    759 : 'Cheyenne, WY',
    760 : 'Twin Falls, ID',
    762 : 'Missoula, MT',
    764 : 'Rapid City, SD',
    765 : 'El Paso, TX',
    766 : 'Helena, MT',
    767 : 'Casper-Riverton, WY',
    770 : 'Salt Lake City, UT',
    771 : 'Yuma, AZ',
    773 : 'Grand Junction, CO',
    789 : 'Tucson, AZ',
    790 : 'Albuquerque, NM',
    798 : 'Glendive, MT',
    800 : 'Bakersfield, CA',
    801 : 'Eugene, OR',
    802 : 'Eureka, CA',
    803 : 'Los Angeles, CA',
    804 : 'Palm Springs, CA',
    807 : 'San Francisco, CA',
    810 : 'Yakima-Pasco, WA',
    811 : 'Reno, NV',
    813 : 'Medford-Klamath Falls, OR',
    819 : 'Seattle-Tacoma, WA',
    820 : 'Portland, OR',
    821 : 'Bend, OR',
    825 : 'San Diego, CA',
    828 : 'Monterey-Salinas, CA',
    839 : 'Las Vegas, NV',
    855 : 'Santa Barbara, CA',
    862 : 'Sacramento, CA',
    866 : 'Fresno, CA',
    868 : 'Chico-Redding, CA',
    881 : 'Spokane, WA'
    }

COUNTRY_CODES = (
    '', 'AP', 'EU', 'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AN', 'AO', 'AQ',
    'AR', 'AS', 'AT', 'AU', 'AW', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH',
    'BI', 'BJ', 'BM', 'BN', 'BO', 'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CA',
    'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR', 'CU',
    'CV', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE', 'EG',
    'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'FX', 'GA', 'GB',
    'GD', 'GE', 'GF', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT',
    'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IN',
    'IO', 'IQ', 'IR', 'IS', 'IT', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM',
    'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK', 'LR', 'LS',
    'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN',
    'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA',
    'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA',
    'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY',
    'QA', 'RE', 'RO', 'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI',
    'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'ST', 'SV', 'SY', 'SZ', 'TC', 'TD',
    'TF', 'TG', 'TH', 'TJ', 'TK', 'TM', 'TN', 'TO', 'TL', 'TR', 'TT', 'TV', 'TW',
    'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI', 'VN',
    'VU', 'WF', 'WS', 'YE', 'YT', 'RS', 'ZA', 'ZM', 'ME', 'ZW', 'A1', 'A2', 'O1',
    'AX', 'GG', 'IM', 'JE', 'BL', 'MF'
    )

COUNTRY_CODES3 = (
    '','AP','EU','AND','ARE','AFG','ATG','AIA','ALB','ARM','ANT','AGO','AQ','ARG',
    'ASM','AUT','AUS','ABW','AZE','BIH','BRB','BGD','BEL','BFA','BGR','BHR','BDI',
    'BEN','BMU','BRN','BOL','BRA','BHS','BTN','BV','BWA','BLR','BLZ','CAN','CC',
    'COD','CAF','COG','CHE','CIV','COK','CHL','CMR','CHN','COL','CRI','CUB','CPV',
    'CX','CYP','CZE','DEU','DJI','DNK','DMA','DOM','DZA','ECU','EST','EGY','ESH',
    'ERI','ESP','ETH','FIN','FJI','FLK','FSM','FRO','FRA','FX','GAB','GBR','GRD',
    'GEO','GUF','GHA','GIB','GRL','GMB','GIN','GLP','GNQ','GRC','GS','GTM','GUM',
    'GNB','GUY','HKG','HM','HND','HRV','HTI','HUN','IDN','IRL','ISR','IND','IO',
    'IRQ','IRN','ISL','ITA','JAM','JOR','JPN','KEN','KGZ','KHM','KIR','COM','KNA',
    'PRK','KOR','KWT','CYM','KAZ','LAO','LBN','LCA','LIE','LKA','LBR','LSO','LTU',
    'LUX','LVA','LBY','MAR','MCO','MDA','MDG','MHL','MKD','MLI','MMR','MNG','MAC',
    'MNP','MTQ','MRT','MSR','MLT','MUS','MDV','MWI','MEX','MYS','MOZ','NAM','NCL',
    'NER','NFK','NGA','NIC','NLD','NOR','NPL','NRU','NIU','NZL','OMN','PAN','PER',
    'PYF','PNG','PHL','PAK','POL','SPM','PCN','PRI','PSE','PRT','PLW','PRY','QAT',
    'REU','ROU','RUS','RWA','SAU','SLB','SYC','SDN','SWE','SGP','SHN','SVN','SJM',
    'SVK','SLE','SMR','SEN','SOM','SUR','STP','SLV','SYR','SWZ','TCA','TCD','TF',
    'TGO','THA','TJK','TKL','TLS','TKM','TUN','TON','TUR','TTO','TUV','TWN','TZA',
    'UKR','UGA','UM','USA','URY','UZB','VAT','VCT','VEN','VGB','VIR','VNM','VUT',
    'WLF','WSM','YEM','YT','SRB','ZAF','ZMB','MNE','ZWE','A1','A2','O1',
    'ALA','GGY','IMN','JEY','BLM','MAF'
    )

COUNTRY_NAMES = (
    "", "Asia/Pacific Region", "Europe", "Andorra", "United Arab Emirates",
    "Afghanistan", "Antigua and Barbuda", "Anguilla", "Albania", "Armenia",
    "Netherlands Antilles", "Angola", "Antarctica", "Argentina", "American Samoa",
    "Austria", "Australia", "Aruba", "Azerbaijan", "Bosnia and Herzegovina",
    "Barbados", "Bangladesh", "Belgium", "Burkina Faso", "Bulgaria", "Bahrain",
    "Burundi", "Benin", "Bermuda", "Brunei Darussalam", "Bolivia", "Brazil",
    "Bahamas", "Bhutan", "Bouvet Island", "Botswana", "Belarus", "Belize",
    "Canada", "Cocos (Keeling) Islands", "Congo, The Democratic Republic of the",
    "Central African Republic", "Congo", "Switzerland", "Cote D'Ivoire", "Cook Islands",
    "Chile", "Cameroon", "China", "Colombia", "Costa Rica", "Cuba", "Cape Verde",
    "Christmas Island", "Cyprus", "Czech Republic", "Germany", "Djibouti",
    "Denmark", "Dominica", "Dominican Republic", "Algeria", "Ecuador", "Estonia",
    "Egypt", "Western Sahara", "Eritrea", "Spain", "Ethiopia", "Finland", "Fiji",
    "Falkland Islands (Malvinas)", "Micronesia, Federated States of", "Faroe Islands",
    "France", "France, Metropolitan", "Gabon", "United Kingdom",
    "Grenada", "Georgia", "French Guiana", "Ghana", "Gibraltar", "Greenland",
    "Gambia", "Guinea", "Guadeloupe", "Equatorial Guinea", "Greece",
    "South Georgia and the South Sandwich Islands",
    "Guatemala", "Guam", "Guinea-Bissau",
    "Guyana", "Hong Kong", "Heard Island and McDonald Islands", "Honduras",
    "Croatia", "Haiti", "Hungary", "Indonesia", "Ireland", "Israel", "India",
    "British Indian Ocean Territory", "Iraq", "Iran, Islamic Republic of",
    "Iceland", "Italy", "Jamaica", "Jordan", "Japan", "Kenya", "Kyrgyzstan",
    "Cambodia", "Kiribati", "Comoros", "Saint Kitts and Nevis",
    "Korea, Democratic People's Republic of",
    "Korea, Republic of", "Kuwait", "Cayman Islands",
    "Kazakstan", "Lao People's Democratic Republic", "Lebanon", "Saint Lucia",
    "Liechtenstein", "Sri Lanka", "Liberia", "Lesotho", "Lithuania", "Luxembourg",
    "Latvia", "Libyan Arab Jamahiriya", "Morocco", "Monaco", "Moldova, Republic of",
    "Madagascar", "Marshall Islands", "Macedonia",
    "Mali", "Myanmar", "Mongolia", "Macau", "Northern Mariana Islands",
    "Martinique", "Mauritania", "Montserrat", "Malta", "Mauritius", "Maldives",
    "Malawi", "Mexico", "Malaysia", "Mozambique", "Namibia", "New Caledonia",
    "Niger", "Norfolk Island", "Nigeria", "Nicaragua", "Netherlands", "Norway",
    "Nepal", "Nauru", "Niue", "New Zealand", "Oman", "Panama", "Peru", "French Polynesia",
    "Papua New Guinea", "Philippines", "Pakistan", "Poland", "Saint Pierre and Miquelon",
    "Pitcairn Islands", "Puerto Rico", "Palestinian Territory",
    "Portugal", "Palau", "Paraguay", "Qatar", "Reunion", "Romania",
    "Russian Federation", "Rwanda", "Saudi Arabia", "Solomon Islands",
    "Seychelles", "Sudan", "Sweden", "Singapore", "Saint Helena", "Slovenia",
    "Svalbard and Jan Mayen", "Slovakia", "Sierra Leone", "San Marino", "Senegal",
    "Somalia", "Suriname", "Sao Tome and Principe", "El Salvador", "Syrian Arab Republic",
    "Swaziland", "Turks and Caicos Islands", "Chad", "French Southern Territories",
    "Togo", "Thailand", "Tajikistan", "Tokelau", "Turkmenistan",
    "Tunisia", "Tonga", "Timor-Leste", "Turkey", "Trinidad and Tobago", "Tuvalu",
    "Taiwan", "Tanzania, United Republic of", "Ukraine",
    "Uganda", "United States Minor Outlying Islands", "United States", "Uruguay",
    "Uzbekistan", "Holy See (Vatican City State)", "Saint Vincent and the Grenadines",
    "Venezuela", "Virgin Islands, British", "Virgin Islands, U.S.",
    "Vietnam", "Vanuatu", "Wallis and Futuna", "Samoa", "Yemen", "Mayotte",
    "Serbia", "South Africa", "Zambia", "Montenegro", "Zimbabwe",
    "Anonymous Proxy","Satellite Provider","Other",
    "Aland Islands","Guernsey","Isle of Man","Jersey","Saint Barthelemy","Saint Martin"
    )

# storage / caching flags
STANDARD = 0
MEMORY_CACHE = 1
MMAP_CACHE = 8

# Database structure constants
COUNTRY_BEGIN = 16776960
STATE_BEGIN_REV0 = 16700000
STATE_BEGIN_REV1 = 16000000

STRUCTURE_INFO_MAX_SIZE = 20
DATABASE_INFO_MAX_SIZE = 100

# Database editions
COUNTRY_EDITION = 1
REGION_EDITION_REV0 = 7
REGION_EDITION_REV1 = 3
CITY_EDITION_REV0 = 6
CITY_EDITION_REV1 = 2
ORG_EDITION = 5
ISP_EDITION = 4
PROXY_EDITION = 8
ASNUM_EDITION = 9
NETSPEED_EDITION = 11
COUNTRY_EDITION_V6 = 12

SEGMENT_RECORD_LENGTH = 3
STANDARD_RECORD_LENGTH = 3
ORG_RECORD_LENGTH = 4
MAX_RECORD_LENGTH = 4
MAX_ORG_RECORD_LENGTH = 300
FULL_RECORD_LENGTH = 50

US_OFFSET = 1
CANADA_OFFSET = 677
WORLD_OFFSET = 1353
FIPS_RANGE = 360


