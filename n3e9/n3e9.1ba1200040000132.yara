import "hash"

rule n3e9_1ba1200040000132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1ba1200040000132"
     cluster="n3e9.1ba1200040000132"
     cluster_size="1044 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="allaple rahack jadtre"
     md5_hashes="['19cd761374bdfd1016baa0557b16344c', '29bbf360913bc5f77be0a2d00a412aa3', '0dbecad9d0bf6d965cc1f4457d6c9eb0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(130560,1024) == "bedc31b60d0d07a39db8e3f5a37c10e2"
}

