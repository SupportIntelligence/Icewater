
rule m3ed_19b0d49bc2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.19b0d49bc2200b32"
     cluster="m3ed.19b0d49bc2200b32"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['17554a6a52ad99e20d3c5e6ddd57b8a0','54dcef8ac58318a03dfb5fff8e3c72b2','fadd93fc125b344cd80006ed09d4a25f']"

   strings:
      $hex_string = { 0d40e3001056395004740f8bf16bf60c03750883c00c3bc672ec6bc90c034d085e3bc17305395004740233c05dc3ff3518fb0010e880b9ffff59c36a2068c8c5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
