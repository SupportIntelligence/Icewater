
rule k2318_37138aeedee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37138aeedee30b12"
     cluster="k2318.37138aeedee30b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['506f56db2ba8d2dd6f3864c6fbb7da6d45c081dc','db4f8ff0ab43df5bbbdb6a6bc7dbf06272662105','c8da5461ed5c477ea705bc2e23b720559c9cd6e2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37138aeedee30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
