
rule m3e9_11b994e9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.11b994e9ca000912"
     cluster="m3e9.11b994e9ca000912"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="madangel small madang"
     md5_hashes="['011efb55175b8d0d56a8fb6c9d6c3175','035df0319f87dc28852ffdcf1fbc0254','fcd49615c4b880d288209e50847e9afb']"

   strings:
      $hex_string = { 57696e646f7754687265616450726f636573734964002bccc1e902ffe078037901eb588bcce8180000005265674e6f746966794368616e67654b657956616c75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
