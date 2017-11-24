
rule m3e9_693f85a48fd31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f85a48fd31912"
     cluster="m3e9.693f85a48fd31912"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['4049aef3ba000bd9bca68c1e4c7b666d','414db84f75c2fed537ece08a78043dac','f79e0b406b9d63890d6e7b905eda957a']"

   strings:
      $hex_string = { cf2ac95a624d932c4f659b0ac0554bc8a4048eaaaf40cb8d52817d7e72dde2aaceba573b845eb915779d269f36c6539c2da987e997b7ecbbaed8f34761db05b0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
