
rule n3e9_4098653e6a208932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4098653e6a208932"
     cluster="n3e9.4098653e6a208932"
     cluster_size="489"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['020634f16d9b23712622ee98a13bafad','0240ddc32f5bec85b2a6998b31c7ca26','0ed4dc4a8a91c005be7186ad0729caa0']"

   strings:
      $hex_string = { edefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
