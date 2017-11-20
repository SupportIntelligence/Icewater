
rule m3e9_0692ae99e6210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0692ae99e6210912"
     cluster="m3e9.0692ae99e6210912"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik fawf"
     md5_hashes="['0aded777fa0d86f8fb9ce03608005247','887cc9bb4e72f132420a4a373cc43cb8','cfe80d82e586072e414ec09e39262a27']"

   strings:
      $hex_string = { 6c448197999abbc2bed5cacac6fcdafbfcfbfcfbf25d820338fd0000000000000000000000001bdf865b5b87678b8d8f4d567d7e929396989cb4b5b59f48c5d8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
