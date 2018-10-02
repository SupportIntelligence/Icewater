
rule k2319_392d54a9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.392d54a9c8800932"
     cluster="k2319.392d54a9c8800932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d253f1981682acc78bc4edf92e03ab95f3377cbd','a8a4ea218cebf5c4ff6b16b4b6db6218b3e922ca','ff996068a70d0039bf7adb6385d4620d5b9586c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.392d54a9c8800932"

   strings:
      $hex_string = { 66696e6564297b72657475726e20505b435d3b7d76617220713d282834302c36362e354531293c28307837432c3078323041293f343a307846423e2838322e38 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
