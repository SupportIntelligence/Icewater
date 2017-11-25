
rule m3f7_6a1b149dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6a1b149dc6220b12"
     cluster="m3f7.6a1b149dc6220b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker html"
     md5_hashes="['4b2e0478c0972a8ecabda705016ecad6','6015c2d40b071da9e0ca4566d871d7b4','f9b5262bfcc76ed45b990ab782f5bbc7']"

   strings:
      $hex_string = { 696d6167653a2075726c2822687474703a2f2f332e62702e626c6f6773706f742e636f6d2f2d67504c302d3546585652382f5559786a51316e4c647a492f4141 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
