
rule n3f8_42d16a00c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.42d16a00c0000b12"
     cluster="n3f8.42d16a00c0000b12"
     cluster_size="55"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zdtad androidos inoco"
     md5_hashes="['cda2f479cbdd415cf6e12df2f5e8834d96dc25db','f56e6856940c77dd3b6484de1c1201486506a56f','af5ead4767402a8ded966d2aa9cb76d6d3303aa4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.42d16a00c0000b12"

   strings:
      $hex_string = { bd93e5898de794a8e688b770757368e997b4e99a94e697b6e997b4e4b8ba3d0033426f6f7452656365697665722e73657450757368416c61726d2853505f4b45 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
