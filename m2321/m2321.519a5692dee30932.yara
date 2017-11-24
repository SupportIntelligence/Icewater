
rule m2321_519a5692dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.519a5692dee30932"
     cluster="m2321.519a5692dee30932"
     cluster_size="8"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="emotet enistery pemalform"
     md5_hashes="['0124191c7a012975ecd3aaa6ccd1801f','31ec401472453bfe4576b68d2672f07a','f434dd7d52c28380912252e871913b28']"

   strings:
      $hex_string = { 5baf96e2ab8c14f2ac0e6062693ed038cd31d69dc85399df8612b7c4198e51e670b085934f4bb3847c471c78fe7dcee07490ca0a8039f1ed049c9bb57f590708 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
