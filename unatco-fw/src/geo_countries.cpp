#include "geo.h"

namespace geo {

static const Country kCountries[] = {
    {"AD","Andorra",42.5f,1.5f},{"AE","United Arab Emirates",24.0f,54.0f},{"AF","Afghanistan",33.9f,67.7f},
    {"AG","Antigua and Barbuda",17.1f,-61.8f},{"AL","Albania",41.2f,20.2f},{"AM","Armenia",40.1f,45.0f},
    {"AO","Angola",-11.2f,17.9f},{"AR","Argentina",-34.0f,-64.0f},{"AT","Austria",47.5f,14.5f},
    {"AU","Australia",-25.7f,134.0f},{"AZ","Azerbaijan",40.1f,47.6f},{"BA","Bosnia and Herzegovina",44.2f,17.8f},
    {"BB","Barbados",13.2f,-59.5f},{"BD","Bangladesh",23.7f,90.3f},{"BE","Belgium",50.6f,4.7f},
    {"BF","Burkina Faso",12.3f,-1.6f},{"BG","Bulgaria",42.7f,25.5f},{"BH","Bahrain",26.0f,50.5f},
    {"BI","Burundi",-3.4f,29.9f},{"BJ","Benin",9.3f,2.3f},{"BN","Brunei",4.5f,114.7f},
    {"BO","Bolivia",-16.7f,-64.7f},{"BR","Brazil",-10.8f,-52.9f},{"BS","Bahamas",24.3f,-76.0f},
    {"BT","Bhutan",27.4f,90.4f},{"BW","Botswana",-22.3f,24.7f},{"BY","Belarus",53.7f,27.9f},
    {"BZ","Belize",17.2f,-88.7f},{"CA","Canada",58.0f,-98.0f},{"CD","DR Congo",-2.9f,23.7f},
    {"CF","Central African Republic",6.6f,20.9f},{"CG","Congo",-0.7f,15.2f},{"CH","Switzerland",46.8f,8.2f},
    {"CI","Cote d'Ivoire",7.6f,-5.5f},{"CL","Chile",-37.0f,-71.5f},{"CM","Cameroon",5.7f,12.7f},
    {"CN","China",35.0f,103.0f},{"CO","Colombia",4.1f,-73.0f},{"CR","Costa Rica",9.9f,-84.2f},
    {"CU","Cuba",21.6f,-79.0f},{"CV","Cabo Verde",16.0f,-24.0f},{"CY","Cyprus",35.0f,33.2f},
    {"CZ","Czechia",49.8f,15.5f},{"DE","Germany",51.1f,10.4f},{"DJ","Djibouti",11.8f,42.6f},
    {"DK","Denmark",56.0f,9.5f},{"DM","Dominica",15.4f,-61.4f},{"DO","Dominican Republic",18.9f,-70.5f},
    {"DZ","Algeria",28.2f,2.6f},{"EC","Ecuador",-1.4f,-78.4f},{"EE","Estonia",58.7f,25.5f},
    {"EG","Egypt",26.5f,29.8f},{"ER","Eritrea",15.4f,38.9f},{"ES","Spain",40.0f,-3.6f},
    {"ET","Ethiopia",8.6f,39.6f},{"FI","Finland",64.5f,26.3f},{"FJ","Fiji",-17.8f,178.0f},
    {"FR","France",46.6f,2.5f},{"GA","Gabon",-0.6f,11.8f},{"GB","United Kingdom",54.0f,-2.5f},
    {"GD","Grenada",12.1f,-61.7f},{"GE","Georgia",42.2f,43.5f},{"GH","Ghana",7.9f,-1.0f},
    {"GL","Greenland",72.0f,-40.0f},{"GM","Gambia",13.4f,-15.4f},{"GN","Guinea",10.9f,-10.9f},
    {"GQ","Equatorial Guinea",1.6f,10.5f},{"GR","Greece",39.1f,22.9f},{"GT","Guatemala",15.7f,-90.4f},
    {"GW","Guinea-Bissau",12.0f,-14.9f},{"GY","Guyana",4.8f,-58.9f},{"HK","Hong Kong",22.3f,114.2f},
    {"HN","Honduras",14.8f,-86.6f},{"HR","Croatia",45.1f,15.5f},{"HT","Haiti",19.0f,-72.7f},
    {"HU","Hungary",47.2f,19.4f},{"ID","Indonesia",-2.3f,117.5f},{"IE","Ireland",53.2f,-8.1f},
    {"IL","Israel",31.4f,35.0f},{"IN","India",22.9f,79.6f},{"IQ","Iraq",33.0f,43.7f},
    {"IR","Iran",32.6f,54.3f},{"IS","Iceland",64.9f,-18.6f},{"IT","Italy",42.8f,12.1f},
    {"JM","Jamaica",18.1f,-77.3f},{"JO","Jordan",31.2f,36.8f},{"JP","Japan",37.6f,138.0f},
    {"KE","Kenya",0.5f,37.8f},{"KG","Kyrgyzstan",41.5f,74.6f},{"KH","Cambodia",12.7f,104.9f},
    {"KI","Kiribati",1.9f,-157.4f},{"KM","Comoros",-11.7f,43.3f},{"KN","Saint Kitts and Nevis",17.3f,-62.7f},
    {"KP","North Korea",40.2f,127.2f},{"KR","South Korea",36.4f,127.9f},{"KW","Kuwait",29.3f,47.6f},
    {"KY","Cayman Islands",19.3f,-81.2f},{"KZ","Kazakhstan",48.2f,67.3f},{"LA","Laos",18.5f,103.8f},
    {"LB","Lebanon",33.9f,35.9f},{"LC","Saint Lucia",13.9f,-61.0f},{"LI","Liechtenstein",47.2f,9.5f},
    {"LK","Sri Lanka",7.6f,80.7f},{"LR","Liberia",6.4f,-9.3f},{"LS","Lesotho",-29.6f,28.2f},
    {"LT","Lithuania",55.3f,23.9f},{"LU","Luxembourg",49.8f,6.1f},{"LV","Latvia",56.9f,24.9f},
    {"LY","Libya",27.0f,17.0f},{"MA","Morocco",31.8f,-6.3f},{"MC","Monaco",43.7f,7.4f},
    {"MD","Moldova",47.2f,28.5f},{"ME","Montenegro",42.8f,19.2f},{"MG","Madagascar",-19.4f,46.7f},
    {"MH","Marshall Islands",7.1f,171.2f},{"MK","North Macedonia",41.6f,21.7f},{"ML","Mali",17.4f,-3.5f},
    {"MM","Myanmar",21.2f,96.5f},{"MN","Mongolia",46.8f,103.0f},{"MO","Macao",22.2f,113.5f},
    {"MR","Mauritania",20.3f,-10.3f},{"MT","Malta",35.9f,14.4f},{"MU","Mauritius",-20.3f,57.6f},
    {"MV","Maldives",3.2f,73.2f},{"MW","Malawi",-13.2f,34.3f},{"MX","Mexico",23.9f,-102.5f},
    {"MY","Malaysia",3.8f,102.2f},{"MZ","Mozambique",-17.3f,35.5f},{"NA","Namibia",-22.1f,17.2f},
    {"NE","Niger",17.4f,9.4f},{"NG","Nigeria",9.6f,8.1f},{"NI","Nicaragua",12.8f,-85.0f},
    {"NL","Netherlands",52.2f,5.6f},{"NO","Norway",61.4f,8.5f},{"NP","Nepal",28.3f,84.0f},
    {"NR","Nauru",-0.5f,166.9f},{"NZ","New Zealand",-41.8f,172.8f},{"OM","Oman",20.6f,56.1f},
    {"PA","Panama",8.5f,-80.1f},{"PE","Peru",-9.2f,-74.4f},{"PG","Papua New Guinea",-6.5f,145.2f},
    {"PH","Philippines",12.8f,122.0f},{"PK","Pakistan",29.9f,69.4f},{"PL","Poland",52.1f,19.4f},
    {"PR","Puerto Rico",18.2f,-66.4f},{"PS","Palestine",31.9f,35.2f},{"PT","Portugal",39.6f,-8.0f},
    {"PW","Palau",7.5f,134.6f},{"PY","Paraguay",-23.2f,-58.4f},{"QA","Qatar",25.3f,51.2f},
    {"RO","Romania",45.9f,25.0f},{"RS","Serbia",44.0f,20.8f},{"RU","Russia",61.5f,95.0f},
    {"RW","Rwanda",-2.0f,29.9f},{"SA","Saudi Arabia",24.1f,44.5f},{"SB","Solomon Islands",-9.2f,160.2f},
    {"SC","Seychelles",-4.7f,55.5f},{"SD","Sudan",15.9f,30.0f},{"SE","Sweden",62.8f,16.7f},
    {"SG","Singapore",1.35f,103.8f},{"SI","Slovenia",46.1f,14.8f},{"SK","Slovakia",48.7f,19.5f},
    {"SL","Sierra Leone",8.5f,-11.8f},{"SM","San Marino",43.9f,12.5f},{"SN","Senegal",14.4f,-14.5f},
    {"SO","Somalia",5.9f,46.1f},{"SR","Suriname",4.1f,-55.9f},{"SS","South Sudan",7.3f,30.2f},
    {"ST","Sao Tome and Principe",0.2f,6.6f},{"SV","El Salvador",13.7f,-88.9f},{"SY","Syria",35.0f,38.5f},
    {"SZ","Eswatini",-26.6f,31.5f},{"TD","Chad",15.3f,18.7f},{"TG","Togo",8.5f,0.9f},
    {"TH","Thailand",15.1f,101.0f},{"TJ","Tajikistan",38.5f,71.0f},{"TL","Timor-Leste",-8.8f,125.9f},
    {"TM","Turkmenistan",39.1f,59.4f},{"TN","Tunisia",34.0f,9.6f},{"TO","Tonga",-20.4f,-174.8f},
    {"TR","Turkey",39.1f,35.2f},{"TT","Trinidad and Tobago",10.5f,-61.3f},{"TV","Tuvalu",-8.5f,179.2f},
    {"TW","Taiwan",23.7f,121.0f},{"TZ","Tanzania",-6.3f,34.8f},{"UA","Ukraine",49.0f,31.4f},
    {"UG","Uganda",1.3f,32.4f},{"US","United States",39.8f,-98.6f},{"UY","Uruguay",-32.8f,-56.0f},
    {"UZ","Uzbekistan",41.8f,63.9f},{"VA","Vatican City",41.9f,12.45f},{"VC","Saint Vincent",13.2f,-61.2f},
    {"VE","Venezuela",7.1f,-66.2f},{"VG","British Virgin Islands",18.4f,-64.6f},{"VN","Vietnam",16.6f,106.3f},
    {"VU","Vanuatu",-16.2f,167.7f},{"WS","Samoa",-13.6f,-172.4f},{"XK","Kosovo",42.6f,20.9f},
    {"YE","Yemen",15.9f,47.6f},{"ZA","South Africa",-29.0f,25.1f},{"ZM","Zambia",-13.5f,27.8f},
    {"ZW","Zimbabwe",-19.0f,29.9f},
    // registry pseudo-codes seen in WHOIS
    {"EU","European Union",50.0f,10.0f},
};

const Country* findCountry(const std::string& cc) {
    if (cc.size() != 2) return nullptr;
    char a = cc[0], b = cc[1];
    if (a >= 'a' && a <= 'z') a = (char)(a - 32);
    if (b >= 'a' && b <= 'z') b = (char)(b - 32);
    for (const auto& c : kCountries)
        if (c.cc[0] == a && c.cc[1] == b) return &c;
    return nullptr;
}

}  // namespace geo
