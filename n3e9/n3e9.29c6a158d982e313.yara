import "hash"

rule n3e9_29c6a158d982e313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c6a158d982e313"
     cluster="n3e9.29c6a158d982e313"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor cuegoe malicious"
     md5_hashes="['7bc6848b9a9b0e00cd358edd4fe4bc56', 'c0f9ff29969f81e9071400754dfcfc87', 'dff93afe6ad7cb0eaf028f2189d70f9d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(5136,1028) == "1ebf251d64af3760403e40a9f3e8a108"
}

