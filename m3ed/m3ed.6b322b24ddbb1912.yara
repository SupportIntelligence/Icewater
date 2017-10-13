import "hash"

rule m3ed_6b322b24ddbb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.6b322b24ddbb1912"
     cluster="m3ed.6b322b24ddbb1912"
     cluster_size="150 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b4e631712c15d58735f1cbeda5d9534e', 'ab9437e9280a3d53b894f17af0ed01b9', '751202005df45c9866c5296b875fa48a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(83968,1024) == "8d2fafbf55fcfd78b7856bd91338e652"
}

