
rule m2321_2298129dc6620b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2298129dc6620b16"
     cluster="m2321.2298129dc6620b16"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut midie shodi"
     md5_hashes="['0770e16981df81910e130a32159d120d','32dbee72042656daa0715140d7637f15','5096416ea30bec71bb3d62008df24238']"

   strings:
      $hex_string = { f27e32e3da259f14d62a371018315882403bb6a6d7b966ee41addc1ca48e4ae10717ea79fad796cc877fe90c6dafca02d93ff4864791de90e663f3e4935a8304 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
