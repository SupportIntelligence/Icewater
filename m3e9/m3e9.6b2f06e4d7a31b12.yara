
rule m3e9_6b2f06e4d7a31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f06e4d7a31b12"
     cluster="m3e9.6b2f06e4d7a31b12"
     cluster_size="81"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['03aa71ba89a09452e8dd7a1d842e95b1','0523b200c4c91fb68a6da3346e43a6a5','a33008bb2c8f907594dee40bc9b7d6b9']"

   strings:
      $hex_string = { 93e7345a90afbe3ebf9bc58b42ea46bd74f6756557947e13642aa3608ffee42480250beee806fc5f3da4dd08899873d650a7d15655fa01f9835cb21e952d36b6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
