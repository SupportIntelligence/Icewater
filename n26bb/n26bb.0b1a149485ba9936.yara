
rule n26bb_0b1a149485ba9936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.0b1a149485ba9936"
     cluster="n26bb.0b1a149485ba9936"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious flystudio akey"
     md5_hashes="['9572074b63f0e6bbbb17034f23d6c9b3c35e74cc','99ad11461ccdc7c1d748aecb9c6a694daf567e96','096316bfe7da9ebd3df1df836730f5d53821df7f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.0b1a149485ba9936"

   strings:
      $hex_string = { b84de5db33352a98aaa5be13913932765150c10fa984266923019b4b1e6d68710db1410a6367536efd576ad6ecfe9d9ee28bee1404303d800ea4c5caadb320ba }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
