
rule o26bb_2b5ad68fc6610916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2b5ad68fc6610916"
     cluster="o26bb.2b5ad68fc6610916"
     cluster_size="1467"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious heuristic attribute"
     md5_hashes="['1327531a152bc085adea49ab5471751c544db098','1b80ec1cbf4e04d728e3074a370ae3d0fc55a1ce','a2b9ae0339422b350d06ed9ec92cb38c729bfd67']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2b5ad68fc6610916"

   strings:
      $hex_string = { e21314c7ea2048ba7bd5f49e4786f6d1d8584fa86ccd1127186eff36089c2b729655dcf030a51f5e448a4ab380eb061989c24699329df2680fb4cfefa3763181 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
