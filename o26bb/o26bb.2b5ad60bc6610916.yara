
rule o26bb_2b5ad60bc6610916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2b5ad60bc6610916"
     cluster="o26bb.2b5ad60bc6610916"
     cluster_size="442"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious attribute bzjn"
     md5_hashes="['714979ff31dd6d31bbdd2056e8955f46cf11f3d2','458312caab7c8b4065e26db197125418b706eee1','935d98c519cd54ca77904b276b8d2ec44723d5d8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2b5ad60bc6610916"

   strings:
      $hex_string = { e21314c7ea2048ba7bd5f49e4786f6d1d8584fa86ccd1127186eff36089c2b729655dcf030a51f5e448a4ab380eb061989c24699329df2680fb4cfefa3763181 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
