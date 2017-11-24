
rule m3e9_748d3ac1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.748d3ac1c8000932"
     cluster="m3e9.748d3ac1c8000932"
     cluster_size="42"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genpack sdld kryptik"
     md5_hashes="['014a11ece0bd6ed8c69511987046f878','039f290868f9b593baf354a7b0aa4486','9a285488922a0849219634ea1e2b3611']"

   strings:
      $hex_string = { ed8e52de45abef364689537c286ea46fd8c268757a9efe0bfbffdd60a7cc4ac8b0afd4ca0576f9fdf8909bfb92b62d1d7ef3dac1078cfa5184818a502ca9961e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
