
rule k3ef_319d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ef.319d6a48c0000b12"
     cluster="k3ef.319d6a48c0000b12"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet malicious corrupt"
     md5_hashes="['00076c2271286d034f68cf5b3aa10657','040bd8750907a9812678b51636c704db','acea18cf9603dae0eee8656e71afca0c']"

   strings:
      $hex_string = { 3a2053797374656d2e5265666c656374696f6e2e417373656d626c795469746c652822446f744e65745a697020534658204172636869766522295d0a00005b61 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
