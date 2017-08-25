import "hash"

rule k3e9_4c12bded5ccbd932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4c12bded5ccbd932"
     cluster="k3e9.4c12bded5ccbd932"
     cluster_size="82 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="autorun spwvpk exploit"
     md5_hashes="['ad58044b783bca19d78c39c2ad32b222', 'aa863ad78d221275c44a5632cb3217fe', 'b08ab2eb205c71475e585f94fe682e7e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16640,256) == "11edd7da4282bf23cafbd9535e7dbc58"
}

