import "hash"

rule n3e9_31ba292bda3b0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ba292bda3b0932"
     cluster="n3e9.31ba292bda3b0932"
     cluster_size="281 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor darkkomet fynloski"
     md5_hashes="['9bcf2b24b79bd6cc1f2808e62a3a2414', 'b48f4d754c175ff047afb30a1d5b3b2e', 'c355deabaa2c90213a025a4ebfc97279']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(172199,1025) == "68c36f1cadc58ccabdaf25ea793106c5"
}

