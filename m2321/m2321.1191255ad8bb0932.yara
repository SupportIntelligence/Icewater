
rule m2321_1191255ad8bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1191255ad8bb0932"
     cluster="m2321.1191255ad8bb0932"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob zusy"
     md5_hashes="['7322d2c3dac5771d07123d30d1a223bc','8382acefd55234f5d54dc06dc9725350','fb4f97f78c7de6ef8b54586401d07b42']"

   strings:
      $hex_string = { 7b4ed2b50f187ab604e072da21a9e120edcd30f82eaa1f6a7ddbbbd0a0fad376125cc2debb80b4aef258d4d90b9c1a43b02a7555f602c779d8d7073c168d34ca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
