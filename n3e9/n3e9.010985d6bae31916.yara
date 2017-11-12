import "hash"

rule n3e9_010985d6bae31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.010985d6bae31916"
     cluster="n3e9.010985d6bae31916"
     cluster_size="7574 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="syncopate unwanted malicious"
     md5_hashes="['089acddd463f3c6cd318f2ded7ab2845', '0670ff2681fdcb4c6ab13de20fb64130', '0d20731c62e8bcd66b31ffbde80dac62']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(565248,1024) == "ead4a97ef9510bb7454b0dd619ef87bd"
}

