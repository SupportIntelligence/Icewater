import "hash"

rule k3e9_6b64d34f9b6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f9b6b5912"
     cluster="k3e9.6b64d34f9b6b5912"
     cluster_size="316 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['a650e307a8ce31fad4d1d96fecc7e13f', 'b3cc2781ac03b00c1c294b65d4d9123a', 'aefa4c07289c216d99f840911cbf14c0']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(23792,1036) == "663025776e46806a4b7c0489da905646"
}

