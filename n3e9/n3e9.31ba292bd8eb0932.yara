import "hash"

rule n3e9_31ba292bd8eb0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ba292bd8eb0932"
     cluster="n3e9.31ba292bd8eb0932"
     cluster_size="1751 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor darkkomet fynloski"
     md5_hashes="['23311beb87f854f3286fa89b1a444b32', '187c62fd247e5bb2f4ab043cc3b3149b', '18befe26e589a225eb2528e0c702bac4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(630272,1024) == "b4f185c39e9f1bdee3a3d63012d57f58"
}

