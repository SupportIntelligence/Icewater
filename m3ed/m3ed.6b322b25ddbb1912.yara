import "hash"

rule m3ed_6b322b25ddbb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.6b322b25ddbb1912"
     cluster="m3ed.6b322b25ddbb1912"
     cluster_size="76 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['f39407d1ba5b5f02c75b6f8ff330e105', 'dcf3f6ecd6804e4859c8844539b6e560', '10c3793a2e8126affbad635a05639d62']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(83968,1024) == "8d2fafbf55fcfd78b7856bd91338e652"
}

