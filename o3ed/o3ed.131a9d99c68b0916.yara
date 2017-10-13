import "hash"

rule o3ed_131a9d99c68b0916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9d99c68b0916"
     cluster="o3ed.131a9d99c68b0916"
     cluster_size="1173 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['3ace420b10c5ddcec25d1bc17c079269', '4e039ac92e0ca44d1d0a3c640ff64608', '791d7f53692032f4489b76f7c6f3f585']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2183168,1024) == "0e6e52e26906a323049b5f94126f2295"
}

