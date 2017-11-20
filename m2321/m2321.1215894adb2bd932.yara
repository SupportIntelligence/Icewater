
rule m2321_1215894adb2bd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1215894adb2bd932"
     cluster="m2321.1215894adb2bd932"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shiz backdoor zusy"
     md5_hashes="['0c71895364ac7001537dd2182eb7fdcf','26191e1131376b58937f855e48d6fc96','f4cc97db26ab7fa5d36aae792638190e']"

   strings:
      $hex_string = { 2a5004c5a15391499eb1ea284b1897d2becbc2004c1610dd6bc9e7a82c1eda1121aec0e459e231539b55d799858c66afba9a79683ea2f9d8d1c164457354d437 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
