
rule m3ed_199d12c1cc840b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.199d12c1cc840b12"
     cluster="m3ed.199d12c1cc840b12"
     cluster_size="213"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="patched ramnit advml"
     md5_hashes="['0227a698b793168bf4eb98b3f575942d','04466a3891e7e0d161e8eb4151442088','15cad1bc9aeb63e2627e89d7778cf453']"

   strings:
      $hex_string = { ffff0900758b704469737061746368575757140041544c20322e302054797065204c6962726172795757230049446f63486f7374554948616e646c6572446973 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
