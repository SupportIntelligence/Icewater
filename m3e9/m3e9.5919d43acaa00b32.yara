
rule m3e9_5919d43acaa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5919d43acaa00b32"
     cluster="m3e9.5919d43acaa00b32"
     cluster_size="178"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader kryptik"
     md5_hashes="['01b0974a61791e68b919a9a2d75bc88f','07e3549a5d731a22e774b28a33e54355','258041ac20a401509b6b5937c74a11b6']"

   strings:
      $hex_string = { 004400490042001a0049006e00760061006c00690064002000730074007200650061006d0020004a00750073007400650066007900740069006f006e00180043 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
