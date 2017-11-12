
rule m3e9_611c91e9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c91e9c2200b16"
     cluster="m3e9.611c91e9c2200b16"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack virut"
     md5_hashes="['274414c60763ddd55965e5591868de82','2b2e7842bb44d1c23ab19dede6f4fe68','c09b839db38393ac1225435382c21410']"

   strings:
      $hex_string = { c82d0309b78b2928d7129a115736bb285cda8b745949236a3fe75c82f46efb1f677c4b5eb87dc542f009371256b5dc56c8868b3df14697814de2a727559a064b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
