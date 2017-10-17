import "hash"

rule n3e9_31ba292bda3b0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ba292bda3b0932"
     cluster="n3e9.31ba292bda3b0932"
     cluster_size="343 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor darkkomet fynloski"
     md5_hashes="['ae38331e561fcb5808b5369ee9e2e60e', '719b79ac3f3ac148a715eab07ee4271e', 'a6f9280f4123c65bdc35e81406fb88dd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(172199,1025) == "68c36f1cadc58ccabdaf25ea793106c5"
}

