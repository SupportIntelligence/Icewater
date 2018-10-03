
rule k26bb_7a98946bc956d311
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.7a98946bc956d311"
     cluster="k26bb.7a98946bc956d311"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu browsefox malicious"
     md5_hashes="['fbcd6f572d39bb4283818741ecb54ed4c4b114ec','d27f1d1d0d253aaf7699d10231a1a0806f7f6a27','31f6bcc16ed9b0f6fb24d7f55b99976659c63c48']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.7a98946bc956d311"

   strings:
      $hex_string = { 53ff15289140005f5e5d5b59c368d4a8400083c00a50e8220a00008bc885c974a88d143703ea3bd1760c2bea8a0288042a4a3bd177f68b6c241c2bcf41eb8c51 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
