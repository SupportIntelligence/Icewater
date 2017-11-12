
rule m3e9_2199a524c3626912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2199a524c3626912"
     cluster="m3e9.2199a524c3626912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte optimuminstaller bundler"
     md5_hashes="['0af0ad8391330e375293f9204936e88d','24cf83d1f675616ed753e519ee640504','ecae9c64323b1f6cc16b142190b7365d']"

   strings:
      $hex_string = { faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3318202333082022f0201013081c93081b4310b3009060355 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
