
rule k2319_690ea949c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.690ea949c0000932"
     cluster="k2319.690ea949c0000932"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browext"
     md5_hashes="['7dd418b74542874090700f660f7fc2765a7531d9','2539392aa83974702f706f4bbb0628641f34d019','0e87239c3e1454b26183d0ed484fad837da99123']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.690ea949c0000932"

   strings:
      $hex_string = { 3e623b7d7d3b2866756e6374696f6e28297b766172204d303d226f77222c44303d226164222c79303d282839342c3132312e293e37352e313045313f277b273a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
