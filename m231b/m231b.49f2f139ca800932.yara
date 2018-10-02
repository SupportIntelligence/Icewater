
rule m231b_49f2f139ca800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.49f2f139ca800932"
     cluster="m231b.49f2f139ca800932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinhive miner script"
     md5_hashes="['0239cd4058532c9ecf69c3aaa91c6d01934f9e15','896778cba543ede5b5a8a9eadc03bd9b236fd8b2','ab3b63718480ab47d5a7c0675b5d4493eb48bf98']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.49f2f139ca800932"

   strings:
      $hex_string = { 6c696420666178206e756d6265722e20466f72206578616d706c65202831323329203435362d37383930206f72203132332d3435362d373839302e223a225c75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
