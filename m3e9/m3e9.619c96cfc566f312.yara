import "hash"

rule m3e9_619c96cfc566f312
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.619c96cfc566f312"
     cluster="m3e9.619c96cfc566f312"
     cluster_size="136 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple madang rahack"
     md5_hashes="['a1381a22b0ae34882c59ec2750c0fe91', 'b51cabd5b315e1a5e1cdb48242d576ca', 'a1381a22b0ae34882c59ec2750c0fe91']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(188000,1030) == "b0d7521531466420dcf3da22bbbd2221"
}

