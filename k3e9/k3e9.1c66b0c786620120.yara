import "hash"

rule k3e9_1c66b0c786620120
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1c66b0c786620120"
     cluster="k3e9.1c66b0c786620120"
     cluster_size="3 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['00c558723b371bae0dc464725075f50d', '932b155714181cc165d4a9755229a269', '00c558723b371bae0dc464725075f50d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14336,1024) == "06205301e9512d0624cf178a60d915b7"
}

