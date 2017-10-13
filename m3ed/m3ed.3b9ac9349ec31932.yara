import "hash"

rule m3ed_3b9ac9349ec31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac9349ec31932"
     cluster="m3ed.3b9ac9349ec31932"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['ddc356edd2608d7ceba975925ab61494', 'e49b5811122e777ee787ddbfbb01378e', 'e5ae9f7f82d634e0bc7ebafb2196d17e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "d8b3e446ad7fc1eeab8a639744aaa5fd"
}

