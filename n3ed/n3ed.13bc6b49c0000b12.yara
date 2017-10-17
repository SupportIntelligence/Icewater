import "hash"

rule n3ed_13bc6b49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.13bc6b49c0000b12"
     cluster="n3ed.13bc6b49c0000b12"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bpchjo"
     md5_hashes="['da65a5395d57db8b9cc303b5e13d1dbe', 'da65a5395d57db8b9cc303b5e13d1dbe', '81b9e1ad6cbeeb0e782934587ca448ac']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(225280,1024) == "6a9067bf3df7b20ec2a3ec638f190d7e"
}

