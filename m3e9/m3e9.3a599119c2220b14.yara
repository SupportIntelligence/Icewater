
rule m3e9_3a599119c2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a599119c2220b14"
     cluster="m3e9.3a599119c2220b14"
     cluster_size="85"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['01f02850eb9884c7e78518a9c7230a70','06c7a0e3abcee64f07b49841b55dea90','a66e0b55ffd70904f37cd320a8cadef7']"

   strings:
      $hex_string = { 0d931e9133819b21c300cac96f0a7c1607ac6c03a22d32cfc1d4f7bc435fc478c64df1024cf1fd849609cbf5b9b290a7ddd19c9e7a2f20d3e7698f4c9960a58d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
