import "hash"

rule i3ed_1b985fabd9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.1b985fabd9eb0912"
     cluster="i3ed.1b985fabd9eb0912"
     cluster_size="775"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor padodor symmi"
     md5_hashes="['00f4e413047bf69d078bca1f8575081f','01028211b38d88c1e54adccb7277a88a','0727d6ad707a8df322419ee0eb4b93b5']"


   condition:
      
      filesize > 4096 and filesize < 16384
      and hash.md5(1024,1024) == "28ecf76ca086167b9945853c637495fe"
}

