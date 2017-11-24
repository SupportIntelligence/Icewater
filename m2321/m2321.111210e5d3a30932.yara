
rule m2321_111210e5d3a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.111210e5d3a30932"
     cluster="m2321.111210e5d3a30932"
     cluster_size="91"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz banker"
     md5_hashes="['00e37587cd526dd389e641e84d42a0a6','04d460e1ee6c04f537b1586a382df860','2ea4291f3d057ee5e8f903fb97d6d8ae']"

   strings:
      $hex_string = { 80da104ddc6201f8644a364ca7cff62cc9585535efc1209675e9fccb78e1606a6d690a22f5c2d5d98f7d477cde65aefdf929e2fe775371673e5a38335144e67e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
