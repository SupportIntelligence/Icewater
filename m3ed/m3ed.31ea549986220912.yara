import "hash"

rule m3ed_31ea549986220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31ea549986220912"
     cluster="m3ed.31ea549986220912"
     cluster_size="58 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bpchjo"
     md5_hashes="['c31b3c57ecef1475e273fb997d1720c3', 'c31b3c57ecef1475e273fb997d1720c3', 'c366129df6681e4763bf6cdb09ba5168']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(53248,1024) == "2e1fd58e17e7ebd34f1ab92566daa558"
}

