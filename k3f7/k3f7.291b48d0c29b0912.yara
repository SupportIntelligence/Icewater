
rule k3f7_291b48d0c29b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.291b48d0c29b0912"
     cluster="k3f7.291b48d0c29b0912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos redirector redir"
     md5_hashes="['1ca2aac57da40651e2040c83085ff379','979457ece84e798b629ed31d396adcb0','ba678b38ed3035bfec8934f2f4003eb8']"

   strings:
      $hex_string = { 6971626b495449657a4664477a5378624c6f4d44544842464a725a4a496e7c624e66525555465959736a4b6f744375456d4e655672616f77677549584c485547 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
