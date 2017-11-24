
rule k3e9_2ca5b123971ba13a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2ca5b123971ba13a"
     cluster="k3e9.2ca5b123971ba13a"
     cluster_size="373"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious backdoor laqma"
     md5_hashes="['07f7c3701270da6c3ae3d310c686fb3d','0d5671bfea42292244c1aca3fa75b08d','321176032a3a2208647fbf7364b94085']"

   strings:
      $hex_string = { 85c074778b5ddc8d45b450ff154cb140008b4db8a164e640008d79fff7d723fe2bf98bf04ef7de1bf683e6f183c6110faff103f33bfe894df8724083f801745c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
